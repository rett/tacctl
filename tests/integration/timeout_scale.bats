#!/usr/bin/env bats
# Integration tests for the timing scale (0.2.22): `config devices
# timeout-scale` (device.timeout_scale), `scope timeout-scale`
# (timeout_scale_scope.<scope>) and `device timeout-scale` (the device's
# timeout_scale in devices.yaml), their resolution order and where `device show`
# and `scope show` display it, `config validate`, and `rollback` removing it.

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
    T="$TACCTL_BIN_SCRIPT"
    DEVICES="${TACCTL_STATE_DIR}/devices.yaml"
}

plain() {
    output=$(sed 's/\x1b\[[0-9;]*m//g' <<< "$output")
    mapfile -t lines <<< "$output"
}

@test "timeout scale: nothing is set, every timing is as it was and nothing is shown" {
    run "$T" device add sat1 10.99.0.1 --vendor cisco --no-host-key --no-lookup
    assert_success
    run "$T" device timeout-scale sat1
    assert_success
    plain
    assert_output --partial "Timeout scale of device 'sat1': 1  (built in: no scale is set)"
    assert_output --partial "Every timing is as it has always been."
    run "$T" device show sat1
    plain
    refute_output --partial "Timeout scale"
    run "$T" device list --json
    refute_output --partial "timeout_scale"
    [[ ! -e "${TACCTL_STATE_DIR}/tacctl.yaml" ]]
    run grep -c timeout_scale "$DEVICES"
    assert_output "0"
}

@test "timeout scale: the server's, the scope's and the device's own, in that order" {
    run "$T" config devices timeout-scale 2
    assert_success
    assert_output --partial "The timeout scale of the whole server set to 2."
    run "$T" device add sat1 10.99.0.1 --vendor cisco --no-host-key --no-lookup
    assert_success
    scope=prod # 10.0.0.0/8 of the fixture
    run "$T" device timeout-scale sat1
    plain
    assert_output --partial "Timeout scale of device 'sat1': 2  (the default of the whole server, device.timeout_scale)"
    run "$T" scope timeout-scale "$scope" 5
    assert_success
    assert_output --partial "timeout scale: 5."
    run "$T" device timeout-scale sat1
    plain
    assert_output --partial "Timeout scale of device 'sat1': 5  (scope '${scope}')"
    assert_output --partial "SNMP timeout:               10 s"
    run "$T" device timeout-scale sat1 3
    assert_success
    assert_output --partial "Device 'sat1' timeout scale: 3."
    run "$T" device show sat1
    plain
    assert_output --partial "Timeout scale: 3  (the device's own)"
    run "$T" device show sat1 --json
    assert_output --partial '"timeout_scale": {'
    assert_output --partial '"scale": 3'
    run "$T" scope show "$scope"
    plain
    assert_output --partial "Timeout scale:  5  (the scope's own)"
    run grep "timeout_scale: 3" "$DEVICES"
    assert_success
    run "$T" config validate
    assert_success
    run "$T" device timeout-scale sat1 clear
    assert_success
    assert_output --partial "follows its scope's timeout scale again"
    run "$T" scope timeout-scale "$scope" clear
    assert_success
    run "$T" device timeout-scale sat1
    plain
    assert_output --partial "Timeout scale of device 'sat1': 2  (the default of the whole server"
    run grep -c timeout_scale "$DEVICES"
    assert_output "0"
}

@test "timeout scale: a value outside 1 to 10 is refused everywhere" {
    run "$T" device add sat1 10.99.0.1 --vendor cisco --no-host-key --no-lookup
    assert_success
    for bad in 0 11 fast 2.5; do
        run "$T" device timeout-scale sat1 "$bad"
        assert_failure
        run "$T" config devices timeout-scale "$bad"
        assert_failure
    done
    run "$T" scope timeout-scale prod 11
    assert_failure
    assert_output --partial "whole number from 1 to 10"
    [[ ! -e "${TACCTL_STATE_DIR}/tacctl.yaml" ]]
}

@test "timeout scale: config validate reports a hand-edited value" {
    printf 'device:\n  timeout_scale: 11\n' > "${TACCTL_STATE_DIR}/tacctl.yaml"
    run "$T" config validate
    assert_failure
    assert_output --partial "device.timeout_scale"
}

# The older releases refuse the keys, so every rollback target removes them
# after a snapshot, from tacctl.yaml and devices.yaml, and the dry run writes
# nothing.
@test "rollback: the timing scale goes from both files, for every target, and the dry run writes nothing" {
    export TACCTL_TIER_SUDOERS_FILE="${BATS_TEST_TMPDIR}/sudoers.d/tacctl-tiers"
    stub_cmd visudo
    stub_cmd install 'cp "${@: -2:1}" "${@: -1}"'
    stub_cmd id 'echo "users"'
    "$T" scope secret prod set "0123456789abcdef0123456789abcdef" > /dev/null
    "$T" device add sat1 10.99.0.1 --vendor cisco --no-host-key --no-lookup > /dev/null
    "$T" config devices timeout-scale 3 > /dev/null
    "$T" scope timeout-scale prod 2 > /dev/null
    "$T" device timeout-scale sat1 4 > /dev/null
    before=$(sha256sum "${TACCTL_STATE_DIR}/tacctl.yaml" "$DEVICES")
    for target in 0.2.21 0.2.9; do
        run "$T" rollback "$target"
        assert_success
        assert_output --partial "remove device.timeout_scale"
        assert_output --partial "remove timeout_scale_scope.prod"
        assert_output --partial "remove the timeout_scale key of sat1 (4)"
        assert_output --partial "The timing scale (tacctl device timeout-scale, scope timeout-scale and config devices timeout-scale) is removed"
        assert_output --partial "This was a dry run: nothing was changed."
        [[ "$(sha256sum "${TACCTL_STATE_DIR}/tacctl.yaml" "$DEVICES")" == "$before" ]]
    done
    run "$T" rollback 0.2.21 --apply --yes
    assert_success
    assert_output --partial "removed the timeout scale of 1 device"
    assert_output --partial "Until the upgrade, do not run 'tacctl device timeout-scale', 'tacctl scope timeout-scale' or 'tacctl config devices timeout-scale'"
    # tacctl.yaml held nothing else: the file goes with its last key
    [[ ! -e "${TACCTL_STATE_DIR}/tacctl.yaml" ]]
    run grep -c timeout_scale "$DEVICES"
    assert_output "0"
    run "$T" device list
    assert_success
    run "$T" rollback 0.2.21 --apply
    assert_success
    assert_output --partial "Nothing to convert"
}
